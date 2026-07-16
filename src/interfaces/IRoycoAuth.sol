// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1
pragma solidity ^0.8.28;

/// @title IRoycoAuth
/// @notice Interface for the access control and pausability surface shared by all Royco periphery contracts
interface IRoycoAuth {
    /// @notice Thrown when an address is set to the null address
    error NULL_ADDRESS();

    /// @notice Pauses the contract
    /// @dev Only callable by accounts authorized by the contract's access manager
    function pause() external;

    /// @notice Unpauses the contract
    /// @dev Only callable by accounts authorized by the contract's access manager
    function unpause() external;
}
