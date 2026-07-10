// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { TransparentUpgradeableProxy } from "../../lib/openzeppelin-contracts-v4/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { IRoycoVaultTranche } from "../interfaces/IRoycoVaultTranche.sol";
import { PendleERC20SYUpgV2, PendleRoycoTrancheSY } from "./PendleRoycoTrancheSY.sol";

/**
 * @title PendleRoycoTrancheSYFactory
 * @author Shivaansh Kapoor, Ankur Dubey
 * @notice Permissionless factory that deploys upgradeable Pendle SYs for Royco tranche shares
 * @dev Each SY is deployed behind an OZ v4.9.3 TransparentUpgradeableProxy administered by Pendle's ProxyAdmin,
 *      Ownership transferred to Pendle's pause controller to be compliant with Pendle's deployment requirements.
 * @dev Tranche provenance is intentionally not verified: SY consumers are responsible for vetting the tranche an SY is
 *      deployed for, and omitting the factory lookup keeps deployments protocol-agnostic (Royco Dawn and Day)
 */
contract PendleRoycoTrancheSYFactory {
    /// @notice Pendle's canonical proxy admin
    address public constant PENDLE_PROXY_ADMIN = 0xA28c08f165116587D4F3E708743B4dEe155c5E64;

    /// @notice Pendle's pause controller and SY owner
    address public constant PENDLE_PAUSE_CONTROLLER = 0x2aD631F72fB16d91c4953A7f4260A97C2fE2f31e;

    /// @notice The deployed Pendle SY for each (Royco tranche, offchain reward manager) pair
    mapping(address tranche => mapping(address offchainRewardManager => address sy)) public trancheToOffchainRewardManagerToSY;

    /**
     * @notice Emitted when a Pendle SY is deployed for a tranche
     * @param tranche The Royco tranche the SY was deployed for
     * @param sy The deployed SY proxy
     * @param implementation The SY implementation behind the proxy
     */
    event SYDeployed(address indexed tranche, address indexed sy, address indexed implementation);

    /// @dev Thrown when an address is set to the null address
    error NULL_ADDRESS();

    /// @dev Thrown when an SY has already been deployed for the specified tranche
    error SY_ALREADY_DEPLOYED();

    /**
     * @notice Deploys a Pendle SY for the specified Royco tranche
     * @param _tranche The Royco tranche to deploy the SY for
     * @param _offchainRewardManager The offchain reward manager (zero if the SY has no offchain rewards)
     * @return sy The deployed SY proxy address
     */
    function deploySY(address _tranche, address _offchainRewardManager) external returns (address sy) {
        // Validate that an SY hasn't been deployed already for this (tranche, reward manager) pair
        require(_tranche != address(0), NULL_ADDRESS());
        require(trancheToOffchainRewardManagerToSY[_tranche][_offchainRewardManager] == address(0), SY_ALREADY_DEPLOYED());

        // Deploy the SY implementation with its immutable arguments
        address implementation = address(new PendleRoycoTrancheSY(_tranche, _offchainRewardManager));

        // Marshal the initialization data for the SY proxy with Pendle's pause controller set as the owner
        bytes memory initData = abi.encodeCall(
            PendleERC20SYUpgV2.initialize,
            (
                string(abi.encodePacked("SY ", IRoycoVaultTranche(_tranche).name())),
                string(abi.encodePacked("SY-", IRoycoVaultTranche(_tranche).symbol())),
                PENDLE_PAUSE_CONTROLLER
            )
        );

        // Deploy the tranche SY proxy: Pendle requires the v4.9.3 transparent proxy with their proxy admin set directly as the admin
        trancheToOffchainRewardManagerToSY[_tranche][_offchainRewardManager] = sy = address(
            new TransparentUpgradeableProxy(implementation, PENDLE_PROXY_ADMIN, initData)
        );
        emit SYDeployed(_tranche, sy, implementation);
    }
}
