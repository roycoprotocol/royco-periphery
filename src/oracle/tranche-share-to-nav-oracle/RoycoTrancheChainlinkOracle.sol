// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { IRoycoVaultTranche } from "../../interfaces/IRoycoVaultTranche.sol";
import { AggregatorV3Interface } from "../../interfaces/external/chainlink/AggregatorV3Interface.sol";
import { WAD, WAD_DECIMALS } from "../../libraries/Constants.sol";
import { PeripheryUtilsLib } from "../../libraries/PeripheryUtilsLib.sol";
import { toInt256 } from "../../libraries/Units.sol";

/**
 * @title RoycoTrancheChainlinkOracle
 * @author Shivaansh Kapoor, Ankur Dubey
 * @notice A Chainlink compatible oracle exposing the price of 1 share of a Royco tranche in its NAV units (USD, BTC, ETH, etc.)
 * @dev Not usable through the Royco quoters until the tranche has non-zero supply and non-zero NAV: a zero-supply Royco Dawn
 *      tranche's share price query reverts (bubbled here), a zero-supply or wiped Royco Day tranche answers 0, and both
 *      protocols' Chainlink quoters reject non-positive answers — sequence deployments accordingly
 */
contract RoycoTrancheChainlinkOracle is AggregatorV3Interface {
    /// @notice The address of the Royco tranche that this oracle prices 1 share for in NAV units (USD, BTC, ETH, etc.)
    address public immutable ROYCO_TRANCHE;

    /// @notice Constructs the share price oracle for the specified Royco tranche
    /// @param _roycoTranche The Royco tranche that this oracle will be configured for
    constructor(address _roycoTranche) {
        ROYCO_TRANCHE = _roycoTranche;
    }

    /// @inheritdoc AggregatorV3Interface
    /// @notice All Royco tranches use 18 (WAD) decimals of precision for their NAV units
    function decimals() external pure override(AggregatorV3Interface) returns (uint8) {
        return uint8(WAD_DECIMALS);
    }

    /// @inheritdoc AggregatorV3Interface
    function description() external view override(AggregatorV3Interface) returns (string memory) {
        return string(abi.encodePacked("Returns the price of 1 share of ", IRoycoVaultTranche(ROYCO_TRANCHE).name(), " in its NAV units (USD, BTC, ETH, etc.)"));
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
     * @notice The price returned is the price of 1 share of the Royco tranche in its NAV units (USD, BTC, ETH, etc.)
     * @dev Compatible with both Royco Dawn and Royco Day tranches; a reverting tranche query bubbles up its revert reason
     */
    function latestRoundData()
        public
        view
        override(AggregatorV3Interface)
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // Return the NAV of the asset claims tied to 1 tranche share (1e18 == WAD)
        return (1, toInt256(PeripheryUtilsLib.convertToNAV(ROYCO_TRANCHE, WAD)), block.timestamp, block.timestamp, 1);
    }
}
