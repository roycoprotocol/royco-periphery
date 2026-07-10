// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { IRoycoVaultTranche } from "../../src/interfaces/IRoycoVaultTranche.sol";
import { WAD } from "../../src/libraries/Constants.sol";
import { TRANCHE_UNIT } from "../../src/libraries/Units.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { RoycoTrancheBaseAssetChainlinkOracle } from "../../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracle.sol";

import { MockTranche } from "../mock/MockTranche.sol";

/// @title MockKernel
/// @notice Minimal kernel mock exposing the ST and JT asset getters consumed by the base asset oracle
contract MockKernel {
    address public immutable ST_ASSET;
    address public immutable JT_ASSET;

    constructor(address _stAsset, address _jtAsset) {
        ST_ASSET = _stAsset;
        JT_ASSET = _jtAsset;
    }
}

/// @title RoycoTrancheBaseAssetChainlinkOracleTest
/// @notice Unit tests for RoycoTrancheBaseAssetChainlinkOracle backed by MockTranche
/// @dev The oracle sums the first two words of the tranche's convertToAssets return data, which are positionally
///      stable across Royco Dawn's three-word and Royco Day's five-word AssetClaims encodings
contract RoycoTrancheBaseAssetChainlinkOracleTest is Test {
    ERC20Mock internal baseAsset;
    MockTranche internal seniorTranche;
    MockKernel internal kernel;
    RoycoTrancheBaseAssetChainlinkOracle internal oracle;

    function setUp() external {
        baseAsset = new ERC20Mock();
        seniorTranche = new MockTranche(address(baseAsset), address(this), TrancheType.SENIOR);
        kernel = new MockKernel(address(baseAsset), address(baseAsset));
        seniorTranche.setKernel(address(kernel));
        oracle = new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /// @notice Constructor rejects liquidity tranches: their claims live in the ltAssets/stShares words this oracle never reads
    function test_constructor_revertsForLiquidityTranche() external {
        MockTranche liquidityTranche = new MockTranche(address(baseAsset), address(this), TrancheType.LIQUIDITY);
        liquidityTranche.setKernel(address(kernel));

        vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracle.LIQUIDITY_TRANCHES_NOT_SUPPORTED.selector);
        new RoycoTrancheBaseAssetChainlinkOracle(address(liquidityTranche));
    }

    /// @notice Constructor rejects tranches whose market has differing ST and JT assets
    function test_constructor_revertsWhenAssetsDiffer() external {
        MockKernel mixedKernel = new MockKernel(address(baseAsset), makeAddr("OtherAsset"));
        MockTranche mixedTranche = new MockTranche(address(baseAsset), address(this), TrancheType.SENIOR);
        mixedTranche.setKernel(address(mixedKernel));

        vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracle.ST_AND_JT_ASSETS_MUST_BE_IDENTICAL.selector);
        new RoycoTrancheBaseAssetChainlinkOracle(address(mixedTranche));
    }

    /// @notice The answer is the sum of the first two words of a Royco Day shaped (five word) convertToAssets return
    function test_latestRoundData_sumsFirstTwoWords_dayFiveWordReturn() external {
        // Configure the Day shape (two protocol specific middle words); at a 2x share price, 1e18 shares are worth 2e18 base assets
        seniorTranche.setConvertToAssetsMiddleWords(2);
        baseAsset.mint(address(this), 10e18);
        baseAsset.approve(address(seniorTranche), 10e18);
        seniorTranche.deposit(_toTrancheUnits(10e18), address(this));
        seniorTranche.setSharePrice(2e18);

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, 2e18, "Answer should be the ST asset claim for 1 whole share");
    }

    /// @notice The answer is the sum of the first two words of a Royco Dawn shaped (three word) convertToAssets return
    function test_latestRoundData_sumsFirstTwoWords_dawnThreeWordReturn() external {
        // Simulate a Dawn tranche: convertToAssets(WAD) returns exactly three words (stAssets, jtAssets, nav)
        vm.mockCall(
            address(seniorTranche),
            abi.encodeCall(IRoycoVaultTranche.convertToAssets, (WAD)),
            abi.encode(uint256(3e18), uint256(1e18), uint256(4e18))
        );

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, 4e18, "Answer should sum the stAssets and jtAssets words of a three word return");
    }

    /// @notice A reverting tranche query surfaces as the Chainlink conventional "No data present" revert
    function test_latestRoundData_revertsNoDataPresent_whenQueryReverts() external {
        vm.mockCallRevert(address(seniorTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (WAD)), "SOME_TRANCHE_ERROR");

        vm.expectRevert(bytes("No data present"));
        oracle.latestRoundData();
    }

    /// @notice getRoundData only serves round 1
    function test_getRoundData_revertsForInvalidRound() external {
        vm.expectRevert(bytes("No data present"));
        oracle.getRoundData(2);
    }

    /// @notice The oracle reports the base asset's decimals
    function test_decimals_matchesBaseAsset() external view {
        assertEq(oracle.decimals(), 18, "Decimals should mirror the base asset");
    }

    /// @notice The description names the tranche and its base asset symbol
    function test_description_namesTrancheAndBaseAsset() external view {
        assertEq(
            oracle.description(),
            string(abi.encodePacked("Returns the price of 1 share of ", seniorTranche.name(), " in its base asset (", baseAsset.symbol(), ")")),
            "Description should name the tranche and base asset"
        );
    }

    /// @notice The oracle reports version 1
    function test_version_isOne() external view {
        assertEq(oracle.version(), 1, "Version should be 1");
    }

    /// @notice getRoundData for round 1 mirrors latestRoundData
    function test_getRoundData_roundOneMirrorsLatest() external view {
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = oracle.getRoundData(1);
        (uint80 latestRoundId, int256 latestAnswer, uint256 latestStartedAt, uint256 latestUpdatedAt, uint80 latestAnsweredInRound) = oracle.latestRoundData();
        assertEq(roundId, latestRoundId, "Round IDs should match");
        assertEq(answer, latestAnswer, "Answers should match");
        assertEq(startedAt, latestStartedAt, "Started timestamps should match");
        assertEq(updatedAt, latestUpdatedAt, "Updated timestamps should match");
        assertEq(answeredInRound, latestAnsweredInRound, "Answered in round should match");
    }

    /// @dev Wraps a raw amount as tranche units for MockTranche calls
    function _toTrancheUnits(uint256 _amount) internal pure returns (TRANCHE_UNIT) {
        return TRANCHE_UNIT.wrap(_amount);
    }

    /// @notice The answer is correct for any return shape honoring the mandate: leading claims, trailing NAV, anything between
    function test_latestRoundData_sumsFirstTwoWords_anyMiddleWordCount() external {
        baseAsset.mint(address(this), 10e18);
        baseAsset.approve(address(seniorTranche), 10e18);
        seniorTranche.deposit(_toTrancheUnits(10e18), address(this));
        seniorTranche.setSharePrice(2e18);

        uint256[4] memory middleWordCounts = [uint256(0), 1, 5, 16];
        for (uint256 i = 0; i < middleWordCounts.length; i++) {
            seniorTranche.setConvertToAssetsMiddleWords(middleWordCounts[i]);
            (, int256 answer,,,) = oracle.latestRoundData();
            assertEq(answer, 2e18, "Answer should sum the two leading claim words regardless of the middle word count");
        }
    }

    /// @notice Fuzz: the answer sums the two leading claim words for any middle word count and share price honoring the mandate
    /// @param _middleWords The number of arbitrary protocol specific words encoded between the claims and the NAV
    /// @param _sharePriceWAD The tranche share price in WAD
    function testFuzz_latestRoundData_sumsFirstTwoWords_anyShape(uint256 _middleWords, uint256 _sharePriceWAD) external {
        _middleWords = bound(_middleWords, 0, 64);
        _sharePriceWAD = bound(_sharePriceWAD, 0, type(uint128).max);
        seniorTranche.setConvertToAssetsMiddleWords(_middleWords);
        seniorTranche.setSharePrice(_sharePriceWAD);

        (, int256 answer,,,) = oracle.latestRoundData();
        // For 1e18 shares of a senior tranche at the configured price, the ST claim equals the share price and the JT claim is zero
        assertEq(answer, int256(_sharePriceWAD), "Answer should sum the leading claim words for any mandate honoring shape");
    }
}
