// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { console2 } from "../../lib/forge-std/src/console2.sol";
import {
    RoycoTrancheBaseAssetChainlinkOracleFactory
} from "../../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracleFactory.sol";
import { Create2DeployUtils } from "../utils/Create2DeployUtils.sol";

/**
 * @title DeployTrancheBaseAssetChainlinkOracleFactoryScript
 * @notice Deploys the RoycoTrancheBaseAssetChainlinkOracleFactory deterministically via CREATE2.
 *         Same factory address on every chain.
 *
 * Environment variables:
 *   DEPLOYER_PRIVATE_KEY - Key for the deployer account
 */
contract DeployTrancheBaseAssetChainlinkOracleFactoryScript is Create2DeployUtils {
    /// @dev CREATE2 salt for the oracle factory
    bytes32 internal constant ORACLE_FACTORY_SALT = keccak256("ROYCO_TRANCHE_BASE_ASSET_CHAINLINK_ORACLE_FACTORY");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        bytes memory creationCode = type(RoycoTrancheBaseAssetChainlinkOracleFactory).creationCode;

        vm.startBroadcast(deployerPrivateKey);
        (address oracleFactory, bool alreadyDeployed) = deployWithSanityChecks(ORACLE_FACTORY_SALT, creationCode, false);
        vm.stopBroadcast();

        console2.log(alreadyDeployed ? "Oracle Factory already deployed at:" : "Oracle Factory deployed at:", oracleFactory);
    }
}
