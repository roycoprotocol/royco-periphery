// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { AccessManagerUpgradeable } from "../../lib/openzeppelin-contracts-upgradeable/contracts/access/manager/AccessManagerUpgradeable.sol";
import { UUPSUpgradeable } from "../../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { RolesConfiguration } from "./RolesConfiguration.sol";

/**
 * @title RoycoAuthorityMock
 * @notice Test double mirroring the Royco authority (access manager) surface exercised by periphery tests
 * @dev The production Royco authority is an AccessManagerUpgradeable + UUPSUpgradeable singleton that acts as the access
 *      manager authority for every Royco market contract (and for the periphery syncer). Periphery tests only exercise
 *      that access-manager surface — initialize semantics, role grants, canCall/getTargetFunctionRole queries, and the
 *      scheduled-operations expiry — so this mock reproduces exactly those parts of the authority's
 *      initialization flow without any of the market deployment machinery
 */
contract RoycoAuthorityMock is AccessManagerUpgradeable, RolesConfiguration, UUPSUpgradeable {
    /// @notice Configuration for assigning a role, mirrored from the production Royco authority
    /// @custom:field role - The role to assign
    /// @custom:field roleAdminRole - The admin role for the assigned role
    /// @custom:field assignee - The address to assign the role to
    /// @custom:field executionDelay - The execution delay for the assignee's role operations
    struct RoleAssignmentConfiguration {
        uint64 role;
        uint64 roleAdminRole;
        address assignee;
        uint32 executionDelay;
    }

    /// @dev Thrown when the scheduled operations expiry is invalid (zero)
    error INVALID_SCHEDULED_OPERATIONS_EXPIRY_SECONDS();

    /// @dev Thrown when the new implementation for this contract is invalid
    error INVALID_IMPLEMENTATION();

    /// @dev The expiry time for scheduled operations in seconds
    uint32 private _scheduledOperationsExpirySeconds;

    /// @dev Disable the initializers, mirroring the production authority's constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the authority mock, mirroring the parts of the production authority initialization observed by tests
     * @param _admin The admin of the authority
     * @param _deployer The deployer address that can deploy new markets
     * @param _expirySeconds The expiry time for scheduled operations in seconds
     * @param _roles The roles to assign on the authority
     */
    function initialize(
        address _admin,
        address _deployer,
        uint32 _expirySeconds,
        RoleAssignmentConfiguration[] calldata _roles
    )
        external
        virtual
        initializer
    {
        // Initialize the access manager
        __AccessManager_init(_admin);

        // Set the scheduled operations expiry seconds
        require(_expirySeconds != 0, INVALID_SCHEDULED_OPERATIONS_EXPIRY_SECONDS());
        _scheduledOperationsExpirySeconds = _expirySeconds;

        // Grant the deployer the deployer role
        _grantRole(DEPLOYER_ROLE, _deployer, 0, 0);

        // Configure the upgrader role
        _setTargetFunctionRole(address(this), UUPSUpgradeable.upgradeToAndCall.selector, ADMIN_UPGRADER_ROLE);

        // Configure all other market roles (mirrors the production authority's role-assignment loop)
        for (uint256 i = 0; i < _roles.length; i++) {
            RoleAssignmentConfiguration calldata roleAssignment = _roles[i];

            // Get role config to set up admin and guardian
            RoleConfig memory roleConfig = getRoleConfig(roleAssignment.role);

            // Grant the role to the assignee (skip if assignee is zero, e.g., ST_LP_ROLE which is handled separately)
            if (roleAssignment.assignee != address(0)) {
                _grantRole(roleAssignment.role, roleAssignment.assignee, 0, roleAssignment.executionDelay);
            }

            // Set the role admin if different from default (0)
            if (roleConfig.adminRole != _ADMIN_ROLE) {
                _setRoleAdmin(roleAssignment.role, roleConfig.adminRole);
            }

            // Set the role guardian
            _setRoleGuardian(roleAssignment.role, roleConfig.guardianRole);
        }
    }

    /// @inheritdoc AccessManagerUpgradeable
    function expiration() public view override(AccessManagerUpgradeable) returns (uint32) {
        return _scheduledOperationsExpirySeconds;
    }

    /// @dev Restricts the upgrade to only authorized parties, mirroring the real factory
    function _authorizeUpgrade(address _newImplementation) internal override(UUPSUpgradeable) onlyAuthorized {
        require(_newImplementation.code.length > 0, INVALID_IMPLEMENTATION());
    }
}
