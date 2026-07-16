// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1
pragma solidity ^0.8.28;

import { IERC20Metadata } from "../../../lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IRoycoKernel } from "../../interfaces/IRoycoKernel.sol";
import { IRoycoVaultTranche } from "../../interfaces/IRoycoVaultTranche.sol";
import { AggregatorV3Interface } from "../../interfaces/external/chainlink/AggregatorV3Interface.sol";
import { WAD } from "../../libraries/Constants.sol";
import { TrancheType } from "../../libraries/Types.sol";
import { TRANCHE_UNIT, toUint256 } from "../../libraries/Units.sol";

/**
 * @title RoycoTrancheBaseAssetChainlinkOracle
 * @author Shivaansh Kapoor, Ankur Dubey
 * @notice A Chainlink compatible oracle exposing the price of 1 share of a Royco tranche in its base asset
 * @notice Only compatible with markets where the ST and JT assets are identical, allowing claims on both assets to be summed
 */
contract RoycoTrancheBaseAssetChainlinkOracle is AggregatorV3Interface {
    /// @dev Calldata for querying the asset claims (share price breakdown) of 1 Royco tranche share
    /// @dev 1 whole share for all Royco tranches == 1e18 == WAD
    bytes private constant SHARE_PRICE_QUERY = abi.encodeCall(IRoycoVaultTranche.convertToAssets, (WAD));

    /// @notice The address of the Royco tranche that this oracle prices 1 share for in its base asset
    address public immutable ROYCO_TRANCHE;

    /// @notice The address of the base asset
    address public immutable BASE_ASSET;

    /// @dev The error thrown when the ST and JT assets are not identical
    error ST_AND_JT_ASSETS_MUST_BE_IDENTICAL();

    /// @dev The error thrown when the specified tranche is a liquidity tranche
    error LIQUIDITY_TRANCHES_NOT_SUPPORTED();

    /**
     * @notice Constructs the share price oracle for the specified Royco tranche
     * @dev Liquidity tranches are rejected: a Royco Day LT's claims live entirely in the ltAssets/stShares words of its
     *      convertToAssets return data, so the stAssets/jtAssets words this oracle reads would always price it at zero
     * @param _roycoTranche The Royco tranche that this oracle will be configured for
     */
    constructor(address _roycoTranche) {
        ROYCO_TRANCHE = _roycoTranche;

        // Ensure the tranche is not a liquidity tranche, which would always be priced at zero by this oracle
        require(IRoycoVaultTranche(ROYCO_TRANCHE).TRANCHE_TYPE() != TrancheType.LIQUIDITY, LIQUIDITY_TRANCHES_NOT_SUPPORTED());

        // Set the base asset and ensure that the ST and JT base assets are the same
        IRoycoKernel kernel = IRoycoKernel(IRoycoVaultTranche(ROYCO_TRANCHE).KERNEL());
        require((BASE_ASSET = kernel.ST_ASSET()) == kernel.JT_ASSET(), ST_AND_JT_ASSETS_MUST_BE_IDENTICAL());
    }

    /// @inheritdoc AggregatorV3Interface
    function decimals() external view override(AggregatorV3Interface) returns (uint8) {
        return IERC20Metadata(BASE_ASSET).decimals();
    }

    /// @inheritdoc AggregatorV3Interface
    function description() external view override(AggregatorV3Interface) returns (string memory) {
        return string(
            abi.encodePacked(
                "Returns the price of 1 share of ", IRoycoVaultTranche(ROYCO_TRANCHE).name(), " in its base asset (", IERC20Metadata(BASE_ASSET).symbol(), ")"
            )
        );
    }

    /// @inheritdoc AggregatorV3Interface
    function version() external pure override(AggregatorV3Interface) returns (uint256) {
        return 1;
    }

    /// @inheritdoc AggregatorV3Interface
    /// @notice The specified round ID must be 1 for this oracle
    function getRoundData(uint80 _roundId)
        external
        view
        override(AggregatorV3Interface)
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // Revert if no data is available for the specified round ID
        require(_roundId == 1, "No data present");
        return latestRoundData();
    }

    /**
     * @inheritdoc AggregatorV3Interface
     * @notice The price returned is the price of 1 share of the Royco tranche in its base asset
     * @dev The ST and JT asset claims are read from the first two return-data words of the tranche's share price query, which are positionally stable across Royco Dawn and Day
     */
    function latestRoundData()
        public
        view
        override(AggregatorV3Interface)
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // Get the asset claims tied to 1 tranche share (1e18 == WAD)
        (bool success, bytes memory returnData) = ROYCO_TRANCHE.staticcall(SHARE_PRICE_QUERY);
        // If the call reverts downstream, there is no price available in the latest round
        if (!success) revert("No data present");
        // Read the claims on ST and JT assets from the first two words of the return data
        TRANCHE_UNIT stAssets;
        TRANCHE_UNIT jtAssets;
        assembly ("memory-safe") {
            stAssets := mload(add(returnData, 0x20))
            jtAssets := mload(add(returnData, 0x40))
        }
        // Since the ST and JT assets are identical, the price of 1 tranche share is the sum of the claims on both assets
        return (1, int256(toUint256(stAssets + jtAssets)), block.timestamp, block.timestamp, 1);
    }
}
