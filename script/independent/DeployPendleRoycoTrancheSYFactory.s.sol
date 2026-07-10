// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { PendleRoycoTrancheSYFactory } from "../../src/pendle/PendleRoycoTrancheSYFactory.sol";

import { console2 } from "../../lib/forge-std/src/console2.sol";
import { Create2DeployUtils } from "../utils/Create2DeployUtils.sol";

/**
 * @title DeployPendleRoycoTrancheSYFactoryScript
 * @notice Deploys the PendleRoycoTrancheSYFactory deterministically via CREATE2.
 *         Same factory address on every chain.
 *
 * Environment variables:
 *   DEPLOYER_PRIVATE_KEY - Key for the deployer account
 */
contract DeployPendleRoycoTrancheSYFactoryScript is Create2DeployUtils {
    /// @dev CREATE2 salt for the SY factory
    bytes32 internal constant SY_FACTORY_SALT = keccak256("PENDLE_ROYCO_TRANCHE_SY_FACTORY");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        bytes memory creationCode = type(PendleRoycoTrancheSYFactory).creationCode;

        vm.startBroadcast(deployerPrivateKey);
        (address syFactory, bool alreadyDeployed) = deployWithSanityChecks(SY_FACTORY_SALT, creationCode, false);
        vm.stopBroadcast();

        console2.log(alreadyDeployed ? "Pendle SY Factory already deployed at:" : "Pendle SY Factory deployed at:", syFactory);
    }
}
