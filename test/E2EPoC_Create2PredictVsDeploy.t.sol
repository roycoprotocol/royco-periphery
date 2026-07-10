// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../lib/forge-std/src/Test.sol";
import { ERC20Mock } from "../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import { TrancheType } from "../src/libraries/Types.sol";
import { RoycoTrancheBaseAssetChainlinkOracleFactory } from "../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracleFactory.sol";
import { RoycoTrancheChainlinkOracleFactory } from "../src/oracle/tranche-share-to-nav-oracle/RoycoTrancheChainlinkOracleFactory.sol";
import { MockTranche } from "./mock/MockTranche.sol";

contract PoCKernel {
    address public immutable ST_ASSET;
    address public immutable JT_ASSET;

    constructor(address _stAsset, address _jtAsset) {
        ST_ASSET = _stAsset;
        JT_ASSET = _jtAsset;
    }
}

/// @notice PoC: CREATE2 predict-vs-deploy parity for both oracle factories, multiple tranches
contract E2EPoC_Create2PredictVsDeploy is Test {
    function test_poc_create2PredictMatchesDeploy_bothFactories() external {
        ERC20Mock baseAsset = new ERC20Mock();
        RoycoTrancheBaseAssetChainlinkOracleFactory baFactory = new RoycoTrancheBaseAssetChainlinkOracleFactory();
        RoycoTrancheChainlinkOracleFactory navFactory = new RoycoTrancheChainlinkOracleFactory();

        for (uint256 i = 0; i < 3; i++) {
            MockTranche tranche = new MockTranche(address(baseAsset), address(this), i % 2 == 0 ? TrancheType.SENIOR : TrancheType.JUNIOR);
            tranche.setKernel(address(new PoCKernel(address(baseAsset), address(baseAsset))));

            // Base-asset oracle factory
            address baPredicted = baFactory.predictOracleAddress(address(tranche));
            address baDeployed = baFactory.deployOracle(address(tranche));
            assertEq(baPredicted, baDeployed, "base-asset factory predict != deploy");
            assertGt(baDeployed.code.length, 0, "base-asset oracle has no code");

            // NAV oracle factory
            address navPredicted = navFactory.predictOracleAddress(address(tranche));
            address navDeployed = navFactory.deployOracle(address(tranche));
            assertEq(navPredicted, navDeployed, "nav factory predict != deploy");
            assertGt(navDeployed.code.length, 0, "nav oracle has no code");

            // Distinct products per tranche despite the shared global salt (initcode hash differs by ctor arg)
            assertTrue(baDeployed != navDeployed, "oracles collide across factories");
        }

        // Redeploying for the same tranche must revert (CREATE2 address collision), not silently clobber
        MockTranche again = new MockTranche(address(baseAsset), address(this), TrancheType.SENIOR);
        again.setKernel(address(new PoCKernel(address(baseAsset), address(baseAsset))));
        baFactory.deployOracle(address(again));
        vm.expectRevert();
        baFactory.deployOracle(address(again));
        navFactory.deployOracle(address(again));
        vm.expectRevert();
        navFactory.deployOracle(address(again));
    }
}
