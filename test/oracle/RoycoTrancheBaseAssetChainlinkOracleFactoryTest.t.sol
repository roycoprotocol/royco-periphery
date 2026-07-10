// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { TrancheType } from "../../src/libraries/Types.sol";
import { RoycoTrancheBaseAssetChainlinkOracle } from "../../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracle.sol";
import { RoycoTrancheBaseAssetChainlinkOracleFactory } from
    "../../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracleFactory.sol";

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

/// @title RoycoTrancheBaseAssetChainlinkOracleFactoryTest
/// @notice Unit tests for the permissionless base asset oracle factory
contract RoycoTrancheBaseAssetChainlinkOracleFactoryTest is Test {
    ERC20Mock internal baseAsset;
    MockTranche internal seniorTranche;
    RoycoTrancheBaseAssetChainlinkOracleFactory internal factory;

    /// @notice Mirrors the factory's OracleDeployed event for expectEmit assertions
    event OracleDeployed(address indexed tranche, address indexed oracle);

    function setUp() external {
        baseAsset = new ERC20Mock();
        seniorTranche = new MockTranche(address(baseAsset), address(this), TrancheType.SENIOR);
        seniorTranche.setKernel(address(new MockKernel(address(baseAsset), address(baseAsset))));
        factory = new RoycoTrancheBaseAssetChainlinkOracleFactory();
    }

    /// @notice Deploys an oracle, records the mapping, and emits the deployment event
    function test_deployOracle_deploysRecordsAndEmits() external {
        address predicted = factory.predictOracleAddress(address(seniorTranche));

        vm.expectEmit(true, true, true, true, address(factory));
        emit OracleDeployed(address(seniorTranche), predicted);
        address oracle = factory.deployOracle(address(seniorTranche));

        assertEq(factory.trancheToOracle(address(seniorTranche)), oracle, "The oracle should be recorded for the tranche");
        assertEq(RoycoTrancheBaseAssetChainlinkOracle(oracle).ROYCO_TRANCHE(), address(seniorTranche), "The oracle should be wired to the tranche");
        assertEq(RoycoTrancheBaseAssetChainlinkOracle(oracle).BASE_ASSET(), address(baseAsset), "The oracle should resolve the base asset");
    }

    /// @notice The predicted CREATE2 address must match the actually deployed address
    function test_predictOracleAddress_matchesDeployment() external {
        address predicted = factory.predictOracleAddress(address(seniorTranche));
        address deployed = factory.deployOracle(address(seniorTranche));
        assertEq(deployed, predicted, "Predicted and deployed addresses should match");
    }

    /// @notice Deployment reverts for the null tranche address
    function test_deployOracle_revertsOnNullTranche() external {
        vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracleFactory.NULL_ADDRESS.selector);
        factory.deployOracle(address(0));
    }

    /// @notice Deployment reverts for liquidity tranches via the oracle's constructor guard
    function test_deployOracle_revertsForLiquidityTranche() external {
        MockTranche liquidityTranche = new MockTranche(address(baseAsset), address(this), TrancheType.LIQUIDITY);
        liquidityTranche.setKernel(address(new MockKernel(address(baseAsset), address(baseAsset))));

        vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracle.LIQUIDITY_TRANCHES_NOT_SUPPORTED.selector);
        factory.deployOracle(address(liquidityTranche));
    }
}
