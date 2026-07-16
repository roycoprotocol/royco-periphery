// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1
pragma solidity ^0.8.28;

import { Create2 } from "../../../lib/openzeppelin-contracts/contracts/utils/Create2.sol";
import { RoycoTrancheBaseAssetChainlinkOracle } from "./RoycoTrancheBaseAssetChainlinkOracle.sol";

/**
 * @title RoycoTrancheBaseAssetChainlinkOracleFactory
 * @author Shivaansh Kapoor, Ankur Dubey
 * @notice Permissionless factory that deploys Chainlink compatible oracles for Royco tranche share prices in their base asset
 * @notice Only compatible with markets where the ST and JT assets are identical
 * @dev Tranche provenance is intentionally not verified: oracle consumers are responsible for vetting the tranche an
 *      oracle is deployed for, and omitting the factory lookup keeps deployments protocol-agnostic (Royco Dawn and Day)
 */
contract RoycoTrancheBaseAssetChainlinkOracleFactory {
    /// @dev The global deployment salt used for all oracles
    bytes32 private constant ORACLE_DEPLOYMENT_SALT = keccak256(abi.encode("ROYCO_TRANCHE_BASE_ASSET_CHAINLINK_ORACLE"));

    /// @notice The deployed share price oracle for each Royco tranche
    mapping(address tranche => address oracle) public trancheToOracle;

    /// @notice Emitted when an oracle is deployed for a tranche
    event OracleDeployed(address indexed tranche, address indexed oracle);

    /// @dev Thrown when an address is set to the null address
    error NULL_ADDRESS();

    /**
     * @notice Deploys a share-price oracle for the specified tranche
     * @dev Reverts if the tranche's market doesn't have identical ST and JT assets
     * @param _tranche The Royco tranche to deploy the oracle for
     * @return oracle The deployed oracle's address
     */
    function deployOracle(address _tranche) external returns (address oracle) {
        require(_tranche != address(0), NULL_ADDRESS());
        // Deploy the share price oracle for this tranche
        trancheToOracle[_tranche] = oracle = address(new RoycoTrancheBaseAssetChainlinkOracle{ salt: ORACLE_DEPLOYMENT_SALT }(_tranche));
        emit OracleDeployed(_tranche, oracle);
    }

    /// @notice Predicts the oracle address that would be deployed for the specified tranche
    function predictOracleAddress(address _tranche) external view returns (address) {
        return Create2.computeAddress(
            ORACLE_DEPLOYMENT_SALT, keccak256(abi.encodePacked(type(RoycoTrancheBaseAssetChainlinkOracle).creationCode, abi.encode(_tranche)))
        );
    }
}
